package org.example.expert.domain.todo.dto;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class TodoSearchDto {
    private final Long todoId;
    private final String todoTitle;
    private final Long managerCount;
    private final Long commentCount;
}
