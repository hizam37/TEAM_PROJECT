package socialMedia.exception;

import lombok.Data;

@Data
public class AppError {
    private int httpStatus;
    private String message;

    public AppError(int httpStatus, String message) {
        this.httpStatus = httpStatus;
        this.message = message;
    }
}
