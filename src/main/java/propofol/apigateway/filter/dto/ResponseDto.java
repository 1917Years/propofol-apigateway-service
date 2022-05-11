package propofol.apigateway.filter.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ResponseDto<T> {
    private int status;
    private String result;
    private String message;
    private T data;
}
