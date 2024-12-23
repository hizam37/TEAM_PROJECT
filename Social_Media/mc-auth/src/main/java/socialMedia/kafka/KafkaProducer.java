package socialMedia.kafka;


import socialMedia.dto.RegistrationDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class KafkaProducer {
    private final KafkaTemplate<String, RegistrationDto> kafkaTemplate;

    public void sendMessage(RegistrationDto registrationDto) {
        try {
            kafkaTemplate.send("registerTopic", registrationDto);
        } catch (Exception e) {
            log.error("Failed to send message to Kafka", e);
        }
    }
}
