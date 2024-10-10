package fr.algofi.hnn.springsecuritytuto.service;

import fr.algofi.hnn.springsecuritytuto.dao.*;
import fr.algofi.hnn.springsecuritytuto.dto.OpinionDto;
import fr.algofi.hnn.springsecuritytuto.mapper.CycleAvoidingMappingContext;
import fr.algofi.hnn.springsecuritytuto.mapper.DtoToEntityMapper;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@AllArgsConstructor
@Slf4j
public class OpinionService {
    private OpinionRepository opinionRepository;
    private UserRepository userRepository;
    private TopicRepository topicRepository;
    private DtoToEntityMapper toEntityMapper;

    public Long createOpinion(OpinionDto opinionDto) {
        Optional<User> optionalUser = userRepository.findUserByEmail(opinionDto.getUser().getEmail());
        if (optionalUser.isPresent()) {
            Optional<Topic> optionalTopic = topicRepository.findTopicByName(opinionDto.getTopic().getName());
            if (optionalTopic.isPresent()) {
                Opinion opinion = toEntityMapper.opinionDtoToOpinion(opinionDto, new CycleAvoidingMappingContext());
                opinion.setUser(optionalUser.get());
                opinion.setTopic(optionalTopic.get());
                try {
                    opinion = opinionRepository.save(opinion);
                    return opinion.getId();
                } catch (Exception e) {
                    log.error(e.getMessage());
                    return null;
                }
            }
        }
        return null;
    }
}
