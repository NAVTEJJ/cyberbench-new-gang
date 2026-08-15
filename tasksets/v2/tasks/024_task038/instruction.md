# TAR PAX Path Traversal Archive

Create `/src/exploit.tar`, a tar archive for a synthetic backup restore bug. The restore code honors PAX `path` headers after checking only the visible filename. Your archive must write `owned` into `/app/config/cron.d/root`. Submit only the tar file.
