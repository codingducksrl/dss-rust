/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Predicate;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;

/**
 * The trusted-list file cache ({@code <cache_dir>/tl/}, one file per list, named as DSS's
 * {@code FileCacheDataLoader} names them, so caches seeded by earlier versions and by {@code dss-cli tl refresh}
 * keep working), with the two loaders DSS's job uses, and a safer write path than DSS's own:
 *
 * <ul>
 *   <li>The <b>offline loader</b> reads the cache and nothing else.</li>
 *   <li>The <b>online loader</b> downloads, pre-checks the body ({@link TlDocumentCheck}) and <em>stages</em> it
 *       in a private directory of this refresh under {@code <cache_dir>/tl-staging/}; DSS parses and validates
 *       the staged file. Nothing reaches the
 *       cache until {@link #promote} copies the lists the refresh found usable into it, each through a temporary
 *       file, fsync and an atomic rename. A bad download (an error page, a truncated transfer, a list whose
 *       signature does not validate, or a forged LOTL and the lists it points to) therefore never replaces a good
 *       cached list, and a reader, in this process or another one sharing the directory, never sees a half-written
 *       file.</li>
 * </ul>
 *
 * Both loaders run every document through the {@link Guard} before DSS sees it: the rollback protection of
 * {@link TrustedListManager}, which refuses a list older than the one last published for its URL.
 *
 * <p>One process should own a cache directory: a refresh in another process does not update this one's trust pool.
 * Concurrent writers are nonetheless safe, since every list is renamed into place whole.
 */
final class TlCacheLoader implements AutoCloseable {

    private static final Logger LOG = LoggerFactory.getLogger(TlCacheLoader.class);
    /** Suffix of the staging root, a sibling of the cache directory ({@code <cache_dir>/tl-staging}). */
    private static final String STAGING_SUFFIX = "-staging";
    private static final Duration STALE_STAGING = Duration.ofHours(24);
    private static final AtomicLong REFRESHES = new AtomicLong();

    /** A download of this refresh: where it was staged, or its bytes when the staging directory is unwritable. */
    record Staged(String url, Path file, byte[] bytes) {
    }

    /** What {@link #promote} did: lists copied into the cache, lists left out, and write failures by list URL. */
    record Promotion(int promoted, int skipped, Map<String, String> errors) {
    }

    /** Decides whether a list that passed {@link TlDocumentCheck} may be handed to DSS at all. */
    @FunctionalInterface
    interface Guard {
        /**
         * @param url      the list's URL
         * @param identity what the document says it is
         * @param source   where it comes from, for messages ("download" or the cache file)
         * @throws DSSExternalResourceException to refuse it; DSS then records a download error for the list
         */
        void admit(String url, TlDocumentCheck.Identity identity, String source);
    }

    private final Path dir;
    private final Path stagingRoot;
    private final Guard guard;
    private final ConcurrentHashMap<String, Staged> pending = new ConcurrentHashMap<>();
    private volatile Path stagingDir;
    private volatile boolean stagingUnwritable;

    TlCacheLoader(Path dir, Guard guard) {
        this.dir = dir;
        this.guard = guard;
        this.stagingRoot = dir.resolveSibling(dir.getFileName() + STAGING_SUFFIX);
        removeStaleStaging();
    }

    /** Creates the cache directory; null when it exists now, else why it could not be created (also logged). */
    String ensureDirectory() {
        try {
            Files.createDirectories(dir);
            return null;
        } catch (IOException | RuntimeException e) {
            LOG.warn("Cannot create the trusted-list cache directory {}: {}", dir, e.toString());
            return e.toString();
        }
    }

    /** The cache file of a list, named as DSS names it. */
    Path cacheFile(String url) {
        return dir.resolve(DSSUtils.getNormalizedString(url));
    }

    /** Reads cached lists only; a list that is not cached is a download error for DSS. */
    DSSFileLoader offline() {
        return new Offline(this);
    }

    /**
     * Downloads through {@code http} into this refresh's staging directory. A cached copy younger than
     * {@code expirationMs} (when positive) is served instead of downloading, as DSS's loader does.
     */
    DSSFileLoader online(DataLoader http, long expirationMs) {
        return new Online(this, http, expirationMs);
    }

    /** Starts a refresh: forgets the previous one's downloads and removes its staging directory. */
    void beginRefresh() {
        pending.clear();
        Path previous = stagingDir;
        stagingDir = null;
        stagingUnwritable = false;
        if (previous != null) {
            deleteRecursively(previous);
        }
    }

    /**
     * Copies the downloads of this refresh that {@code promotable} accepts into the cache, atomically each.
     * Downloads it refuses are dropped: the cache keeps whatever it held for them.
     */
    Promotion promote(Predicate<String> promotable) {
        int promoted = 0;
        int skipped = 0;
        Map<String, String> errors = new LinkedHashMap<>();
        if (pending.isEmpty()) {
            return new Promotion(0, 0, errors);
        }
        String dirError = ensureDirectory();
        for (Map.Entry<String, Staged> e : pending.entrySet()) {
            String url = e.getKey();
            if (!promotable.test(url)) {
                skipped++;
                LOG.info("Trusted list {} was downloaded but is not usable: the cache keeps its previous copy", url);
                continue;
            }
            if (dirError != null) {
                errors.put(url, "cache directory " + dir + " cannot be created: " + dirError);
                continue;
            }
            try {
                Staged staged = e.getValue();
                if (staged.file() != null) {
                    writeAtomically(cacheFile(url), Files.readAllBytes(staged.file()));
                } else {
                    writeAtomically(cacheFile(url), staged.bytes());
                }
                promoted++;
            } catch (IOException | RuntimeException ex) {
                errors.put(url, ex.toString());
                LOG.warn("Cannot store trusted list {} in the cache: {}", url, ex.toString());
            }
        }
        pending.clear();
        return new Promotion(promoted, skipped, errors);
    }

    /** Writes {@code bytes} to {@code target} through a temporary sibling, fsync and an atomic rename. */
    static void writeAtomically(Path target, byte[] bytes) throws IOException {
        Path tmp = target.resolveSibling("." + target.getFileName() + ".tmp-" + Long.toHexString(System.nanoTime()));
        try {
            try (FileChannel channel = FileChannel.open(tmp, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                channel.write(java.nio.ByteBuffer.wrap(bytes));
                channel.force(true);
            }
            try {
                Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    /** Stages a download; null when the staging directory cannot be written (the caller keeps the bytes). */
    private Path stage(String url, byte[] bytes) {
        if (stagingUnwritable) {
            return null;
        }
        Path staging = stagingDir;
        if (staging == null) {
            synchronized (this) {
                staging = stagingDir;
                if (staging == null) {
                    staging = stagingRoot.resolve(ProcessHandle.current().pid() + "-" + REFRESHES.incrementAndGet());
                    try {
                        Files.createDirectories(staging);
                    } catch (IOException | RuntimeException e) {
                        LOG.warn("Cannot create the staging directory {}: downloads are kept in memory only ({})",
                                staging, e.toString());
                        stagingUnwritable = true;
                        return null;
                    }
                    stagingDir = staging;
                }
            }
        }
        Path file = staging.resolve(DSSUtils.getNormalizedString(url));
        try {
            writeAtomically(file, bytes);
            return file;
        } catch (IOException | RuntimeException e) {
            LOG.warn("Cannot stage the download of {}: kept in memory only ({})", url, e.toString());
            return null;
        }
    }

    /** Staging directories of refreshes that never finished (a crashed process), older than a day. */
    private void removeStaleStaging() {
        if (!Files.isDirectory(stagingRoot)) {
            return;
        }
        Instant cutoff = Instant.now().minus(STALE_STAGING);
        try (DirectoryStream<Path> entries = Files.newDirectoryStream(stagingRoot)) {
            for (Path entry : entries) {
                FileTime modified = Files.getLastModifiedTime(entry);
                if (modified.toInstant().isBefore(cutoff)) {
                    deleteRecursively(entry);
                }
            }
        } catch (IOException | RuntimeException e) {
            LOG.debug("Cannot clean {}: {}", stagingRoot, e.toString());
        }
    }

    private static void deleteRecursively(Path root) {
        if (!Files.exists(root)) {
            return;
        }
        try (Stream<Path> walk = Files.walk(root)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            });
        } catch (IOException | RuntimeException e) {
            LOG.debug("Cannot remove {}: {}", root, e.toString());
        }
    }

    @Override
    public void close() {
        pending.clear();
        Path staging = stagingDir;
        stagingDir = null;
        if (staging != null) {
            deleteRecursively(staging);
        }
    }

    /** The cached file of {@code url}, pre-checked and admitted by the guard. */
    private DSSDocument checkedFile(String url, Path file) {
        TlDocumentCheck.Identity identity;
        try {
            identity = TlDocumentCheck.check(Files.newInputStream(file), file.toString());
        } catch (IOException e) {
            throw new DSSExternalResourceException("cannot read " + file + ": " + e.getMessage(), e);
        }
        guard.admit(url, identity, file.toString());
        return new FileDocument(file.toFile());
    }

    /** {@link DSSFileLoader} over the cache only. */
    private static final class Offline implements DSSFileLoader {
        private static final long serialVersionUID = 1L;
        private final transient TlCacheLoader cache;

        Offline(TlCacheLoader cache) {
            this.cache = cache;
        }

        @Override
        public DSSDocument getDocument(String url) {
            Path file = cache.cacheFile(url);
            if (!Files.isRegularFile(file)) {
                throw new DSSExternalResourceException("'" + url + "' is not in the trusted-list cache " + cache.dir);
            }
            return cache.checkedFile(url, file);
        }
    }

    /** {@link DSSFileLoader} that downloads into the staging directory; see {@link TlCacheLoader}. */
    private static final class Online implements DSSFileLoader {
        private static final long serialVersionUID = 1L;
        private final transient TlCacheLoader cache;
        private final DataLoader http;
        private final long expirationMs;

        Online(TlCacheLoader cache, DataLoader http, long expirationMs) {
            this.cache = cache;
            this.http = http;
            this.expirationMs = expirationMs;
        }

        @Override
        public DSSDocument getDocument(String url) {
            if (expirationMs > 0) {
                Path cached = cache.cacheFile(url);
                try {
                    if (Files.isRegularFile(cached) && Files.getLastModifiedTime(cached).toMillis() + expirationMs
                            > System.currentTimeMillis()) {
                        LOG.debug("Cached copy of {} is younger than {} ms: not downloaded", url, expirationMs);
                        return cache.checkedFile(url, cached);
                    }
                } catch (IOException e) {
                    LOG.debug("Cannot stat {}: downloading", cached);
                } catch (DSSException e) {
                    // A torn or foreign file (an older version's write, another writer): the network copy may well
                    // be fine, and a download replaces the file. Refusing until the file ages out would keep the
                    // list missing for the whole expiration time.
                    LOG.debug("Cached copy of {} is not usable ({}): downloading", url, e.getMessage());
                }
            }
            byte[] bytes = http.get(url);
            if (bytes == null || bytes.length == 0) {
                throw new DSSExternalResourceException("empty response from '" + url + "'");
            }
            cache.guard.admit(url, TlDocumentCheck.check(new ByteArrayInputStream(bytes), url), "download");
            Path staged = cache.stage(url, bytes);
            if (staged != null) {
                cache.pending.put(url, new Staged(url, staged, null));
                return new FileDocument(staged.toFile());
            }
            cache.pending.put(url, new Staged(url, null, bytes));
            return new InMemoryDocument(bytes, DSSUtils.getNormalizedString(url));
        }
    }

}
