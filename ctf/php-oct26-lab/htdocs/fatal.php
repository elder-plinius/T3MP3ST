<?php
// Request A — fatal with DISTINCTIVE args so a stale backtrace is recognizable.
function t3mp3st_marker_fn(string $secretA, int $secretB): void {
    no_such_function_anywhere_9c41($secretA, $secretB);   // truly undefined -> fatal
}
t3mp3st_marker_fn('T3MARKER-alpha-9c41-zulu', 31337);
