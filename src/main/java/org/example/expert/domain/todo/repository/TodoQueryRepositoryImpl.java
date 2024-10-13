package org.example.expert.domain.todo.repository;

import static org.example.expert.domain.comment.entity.QComment.comment;
import static org.example.expert.domain.manager.entity.QManager.manager;
import static org.example.expert.domain.todo.entity.QTodo.todo;
import static org.example.expert.domain.user.entity.QUser.user;

import com.querydsl.core.types.Predicate;
import com.querydsl.core.types.Projections;
import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.core.types.dsl.Wildcard;
import com.querydsl.jpa.impl.JPAQueryFactory;
import java.time.LocalDateTime;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.example.expert.domain.todo.dto.TodoSearchDto;
import org.example.expert.domain.todo.entity.Todo;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
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
                .leftJoin(todo.user, user).fetchJoin()
                .where(
                        todoIdEq(todoID)
                ).fetchOne();
    }

    @Override
    public Page<TodoSearchDto> search(
            String title,
            String managerNickname,
            LocalDateTime starDate,
            LocalDateTime endDate,
            Pageable pageable
    ) {
        List<TodoSearchDto> results = queryFactory
                .select(
                        Projections.constructor(
                                TodoSearchDto.class,
                                todo.id,
                                todo.title,
                                manager.countDistinct(),
                                comment.countDistinct()
                        )
                )
                .from(todo)
                .leftJoin(todo.managers, manager)
                .leftJoin(todo.user, user)
                .leftJoin(todo.comments, comment)
                .where(
                        titleContains(title),
                        createdAtBetween(starDate, endDate),
                        managerNicknameContains(managerNickname)
                )
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize())
                .groupBy(todo.id)
                .orderBy(todo.id.desc())
                .fetch();

        Long totalCount = queryFactory
                .select(Wildcard.count)
                .from(todo)
                .where(
                        titleContains(title),
                        createdAtBetween(starDate, endDate),
                        managerNicknameContains(managerNickname)
                ).fetchOne();

        return new PageImpl<>(results, pageable, totalCount);
    }


    private BooleanExpression titleContains(String title) {
        return title != null ? todo.title.containsIgnoreCase(title) : null;
    }

    private BooleanExpression createdAtBetween(LocalDateTime starDate, LocalDateTime endDate) {
        if (starDate != null || endDate != null) {
            return todo.createdAt.between(starDate, endDate);
        } else if (starDate != null) {
            return todo.createdAt.after(starDate);
        } else if (endDate != null) {
            return todo.createdAt.before(endDate);
        } else {
            return null;
        }
    }

    private BooleanExpression managerNicknameContains(String managerNickname) {
        return managerNickname != null ? user.nickname.containsIgnoreCase(managerNickname) : null;
    }

    private BooleanExpression todoIdEq(Long todoId) {
        return todoId != null ? todo.id.eq(todoId) : null;
    }
}
