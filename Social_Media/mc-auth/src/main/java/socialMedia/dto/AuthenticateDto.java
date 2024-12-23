package socialMedia.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Schema(description = "DTO аутентификации")
@Data
public class AuthenticateDto {
    private String email;
    private String password;

}

