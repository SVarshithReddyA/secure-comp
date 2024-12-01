package comp3911.cwk2;

import java.util.concurrent.ConcurrentHashMap;
import java.time.Instant;
import java.time.Duration;

public class RateLimiter {
    private static final int MAX_ATTEMPTS = 5; // max 5 attempts allowed in 5 min
    private static final long BLOCK_DURATION_MS = 60000 * 5; // 5 min cool down
    private final ConcurrentHashMap<String, AttemptRecord> attempts = new ConcurrentHashMap<>();

    public boolean isAllowed(String username) {
        AttemptRecord record = attempts.get(username);
        Instant now = Instant.now();

        if (record == null || Duration.between(record.lastAttempt, now).toMillis() > BLOCK_DURATION_MS) {
            // reset after cool down period
            attempts.put(username, new AttemptRecord(1, now));
            return true;
        }

        if (record.count < MAX_ATTEMPTS) {
            // increase attempt cnt
            record.count++;
            record.lastAttempt = now;
            return true;
        }

        return false;
    }

    public void reset(String username) {
        attempts.remove(username);
    }

    private static class AttemptRecord {
        int count;
        Instant lastAttempt;

        AttemptRecord(int count, Instant lastAttempt) {
            this.count = count;
            this.lastAttempt = lastAttempt;
        }
    }
}

