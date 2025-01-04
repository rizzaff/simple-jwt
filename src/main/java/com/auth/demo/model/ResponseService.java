package com.auth.demo.model;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class ResponseService {
    private Object responseData;
    private String responseDesc;
    private String responseCode;
}
