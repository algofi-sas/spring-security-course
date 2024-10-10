package fr.algofi.hnn.springsecuritytuto.dto;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import lombok.Data;

import java.util.List;

@Data
public class TopicDto {
    private String name;
    private String scope;

    @JsonBackReference(value = "user-topics")
    private UserDto user;

    @JsonManagedReference(value = "topic-opinions")
    private List<OpinionDto> opinions;
}
