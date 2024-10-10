package fr.algofi.hnn.springsecuritytuto.controller;

import fr.algofi.hnn.springsecuritytuto.dto.TopicDto;
import fr.algofi.hnn.springsecuritytuto.service.TopicService;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.List;
import java.util.Optional;

@RestController
@AllArgsConstructor
public class TopicController {
    private TopicService service;

    @GetMapping("/topics")
    public ResponseEntity<TopicDto[]> getAllTopics() {
        List<TopicDto> topics = service.getAllTopics();
        return ResponseEntity.ok(topics.toArray(new TopicDto[0]));
    }

    @GetMapping("/topics/{topicId}")
    public ResponseEntity<TopicDto> getTopicsById(@PathVariable Long topicId) {
        Optional<TopicDto> topic = service.getTopicById(topicId);
        if (topic.isPresent()) {
            return ResponseEntity.ok(topic.get());
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @PostMapping("/topics")
    public ResponseEntity<Void> createTopic(@RequestBody TopicDto topicDto, UriComponentsBuilder ucb) {
        Long topicId = service.createTopic(topicDto);
        if (topicId != null) {
            URI locationOfNewTopic = ucb.path("topics/{id}").buildAndExpand(topicId).toUri();
            return ResponseEntity.created(locationOfNewTopic).build();
        } else {
            return ResponseEntity.internalServerError().build();
        }
    }
}
