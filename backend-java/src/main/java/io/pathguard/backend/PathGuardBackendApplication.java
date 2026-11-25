package io.pathguard.backend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class PathGuardBackendApplication {
    public static void main(String[] args) {
        SpringApplication.run(PathGuardBackendApplication.class, args);
    }
}
