package fr.algofi.hnn.springsecuritytuto.controller;

import fr.algofi.hnn.springsecuritytuto.dto.OpinionDto;
import fr.algofi.hnn.springsecuritytuto.service.OpinionService;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

@RestController
@AllArgsConstructor
public class OpinionController {
    private OpinionService service;

    @PostMapping("/topics/{topicId}/opinions")
    public ResponseEntity<Void> createOpinion(@PathVariable Long topicId, @RequestBody OpinionDto opinionDto, UriComponentsBuilder ucb) {
        Long opinionId = service.createOpinion(opinionDto);
        if (opinionId != null) {
            URI locationOfNewOpinion = ucb.path("topics/{topicId}/opinions/{opinionId}").buildAndExpand(topicId, opinionId).toUri();
            return ResponseEntity.created(locationOfNewOpinion).build();
        } else {
            return ResponseEntity.internalServerError().build();
        }
    }
}
