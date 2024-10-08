package org.example.expert.domain.todo.repository;

import static org.example.expert.domain.todo.entity.QTodo.todo;
import static org.example.expert.domain.user.entity.QUser.user;

import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.jpa.impl.JPAQueryFactory;
import lombok.RequiredArgsConstructor;
import org.example.expert.domain.todo.entity.Todo;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class TodoQueryRepositoryImpl implements TodoQueryRepository{
    private final JPAQueryFactory queryFactory;

    @Override
    public Todo findByIdByDsl(long todoID) {
        return queryFactory
                .select(todo)
                .from(todo)
                .join(todo.user, user).fetchJoin()
                .where(
                        todoIdEq(todoID)
                ).fetchOne();

    }

    private BooleanExpression todoIdEq(Long todoId) {
        return todoId != null ? todo.id.eq(todoId) : null;
    }
}
