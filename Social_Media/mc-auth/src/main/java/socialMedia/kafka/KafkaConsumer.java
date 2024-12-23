package socialMedia.kafka;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;
import socialMedia.dto.RegistrationDto;


@Service
@Slf4j
@RequiredArgsConstructor
public class KafkaConsumer {
    private final KafkaProducer kafkaProducer;

    @KafkaListener(topics = "updateTopic", groupId = "${spring.kafka.kafkaMessageGroupId}", containerFactory = "kafkaMessageConcurrentKafkaListenerContainerFactory")
    public void listen(RegistrationDto registrationDto) {
        try {
            log.info("Received registration data: " + registrationDto);
            kafkaProducer.sendMessage(registrationDto);
        } catch (Exception e) {
            log.error("Failed to process message from Kafka", e);
        }
    }
}