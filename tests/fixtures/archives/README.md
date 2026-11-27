# Archive Fixtures

Os containers compactados de teste (ZIP com path traversal, symlinks Unix, ZIP corrompido, TAR com symlink/hardlink e entradas acima do limite de tamanho) são gerados dinamicamente em memória por `tests/archive-reader.test.js` para manter o repositório enxuto e determinístico sem binários maliciosos estáticos.
