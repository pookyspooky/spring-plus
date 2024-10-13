package org.example.expert.domain.todo.repository;

import java.time.LocalDateTime;
import org.example.expert.domain.todo.dto.TodoSearchDto;
import org.example.expert.domain.todo.entity.Todo;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface TodoQueryRepository {
    Todo findByIdByDsl(long todoID);

    Page<TodoSearchDto> search(
            String title,
            String managerNickname,
            LocalDateTime starDate,
            LocalDateTime endDate,
            Pageable pageable
    );
}
