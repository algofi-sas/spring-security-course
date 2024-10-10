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
public interface DtoToEntityMapper {

    User userDtoToUser(UserDto userDto, @Context CycleAvoidingMappingContext context);

    Topic topicDtoToTopic(TopicDto topicDto, @Context CycleAvoidingMappingContext context);

    Opinion opinionDtoToOpinion(OpinionDto opinionDto, @Context CycleAvoidingMappingContext context);
}
