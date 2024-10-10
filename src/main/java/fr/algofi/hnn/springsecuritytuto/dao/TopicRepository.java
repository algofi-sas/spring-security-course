package fr.algofi.hnn.springsecuritytuto.dao;

import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface TopicRepository extends CrudRepository<Topic, Long> {
    Optional<Topic> findTopicByName(String name);
}
