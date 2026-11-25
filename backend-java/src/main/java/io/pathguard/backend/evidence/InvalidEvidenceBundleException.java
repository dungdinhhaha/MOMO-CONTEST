package io.pathguard.backend.evidence;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class InvalidEvidenceBundleException extends RuntimeException {
    public InvalidEvidenceBundleException(String message) {
        super(message);
    }
}
