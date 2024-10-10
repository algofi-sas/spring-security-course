package fr.algofi.hnn.springsecuritytuto.mapper;

import fr.algofi.hnn.springsecuritytuto.dao.Opinion;
import fr.algofi.hnn.springsecuritytuto.dao.Topic;
import fr.algofi.hnn.springsecuritytuto.dao.User;
import fr.algofi.hnn.springsecuritytuto.dto.OpinionDto;
import fr.algofi.hnn.springsecuritytuto.dto.TopicDto;
import fr.algofi.hnn.springsecuritytuto.dto.UserDto;
import org.mapstruct.Context;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface EntityToDtoMapper {

    UserDto userToUserDto(User user, @Context CycleAvoidingMappingContext context);

    TopicDto topicToTopicDto(Topic topic, @Context CycleAvoidingMappingContext context);

    OpinionDto opinionToOpinionDto(Opinion opinion, @Context CycleAvoidingMappingContext context);
}
