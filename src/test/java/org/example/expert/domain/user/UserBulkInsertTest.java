package org.example.expert.domain.user;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.UUID;
import org.example.expert.domain.user.entity.User;
import org.example.expert.domain.user.entity.UserBulkRepository;
import org.example.expert.domain.user.enums.UserRole;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class UserBulkInsertTest {
    @Autowired
    private UserBulkRepository userBulkRepository;

    private static final int TOTAL_USERS = 1_000_000;

    private static final int BATCH_SIZE = 1000;

    @Test
    public void bulkInsertTest() {
        Random random = new Random();

        for (int i = 0; i < TOTAL_USERS; i += BATCH_SIZE) {
            List<User> users = new ArrayList<>();

            for (int j = 0; j < BATCH_SIZE; j++) {
                String email = "user" + UUID.randomUUID() + "@example.org";
                String password = UUID.randomUUID().toString();
                String nickname = "nickname" + random.nextInt(1000000);

                User user = new User(email, password, nickname, UserRole.ROLE_USER);
                users.add(user);
            }

            userBulkRepository.bulkInsert(users);
            pause();
        }
    }

    private void pause() {
        try {
            Thread.sleep(500);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
