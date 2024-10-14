package fr.algofi.hnn.springsecuritytuto.service;

import fr.algofi.hnn.springsecuritytuto.dao.Topic;
import fr.algofi.hnn.springsecuritytuto.dao.TopicRepository;
import fr.algofi.hnn.springsecuritytuto.dao.User;
import fr.algofi.hnn.springsecuritytuto.dao.UserRepository;
import fr.algofi.hnn.springsecuritytuto.dto.TopicDto;
import fr.algofi.hnn.springsecuritytuto.mapper.CycleAvoidingMappingContext;
import fr.algofi.hnn.springsecuritytuto.mapper.DtoToEntityMapper;
import fr.algofi.hnn.springsecuritytuto.mapper.EntityToDtoMapper;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@AllArgsConstructor
@Slf4j
public class TopicService {
    private TopicRepository topicRepository;
    private EntityToDtoMapper toDtoMapper;
    private DtoToEntityMapper toEntityMapper;
    private UserRepository userRepository;

    @PostFilter("filterObject.scope == 'PUBLIC' || hasAnyAuthority('READ_TOPIC', 'WRITE_TOPIC')")
    public List<TopicDto> getAllTopics() {
        Iterable<Topic> ite = topicRepository.findAll();
        List<TopicDto> topics = new ArrayList<>();
        ite.forEach(topic -> topics.add(toDtoMapper.topicToTopicDto(topic, new CycleAvoidingMappingContext())));
        return topics;
    }

    @PostAuthorize("returnObject.get().scope == 'PUBLIC' || hasAnyAuthority('READ_TOPIC', 'WRITE_TOPIC')")
    public Optional<TopicDto> getTopicById(Long topicId) {
        Optional<Topic> topic = topicRepository.findById(topicId);
        return topic.map(value -> toDtoMapper.topicToTopicDto(value, new CycleAvoidingMappingContext()));
    }

    @PreAuthorize("#topicDto.user.email == authentication.principal.username")
    public Long createTopic(TopicDto topicDto) {
        String userEmail = topicDto.getUser().getEmail();
        Optional<User> optionalUser = userRepository.findUserByEmail(userEmail);
        if (optionalUser.isPresent()) {
            Topic topic = toEntityMapper.topicDtoToTopic(topicDto, new CycleAvoidingMappingContext());
            topic.setUser(optionalUser.get());
            try {
                topic = topicRepository.save(topic);
                return topic.getId();
            } catch (Exception e) {
                log.error(e.getMessage());
                return null;
            }
        }
        return null;
    }
}
