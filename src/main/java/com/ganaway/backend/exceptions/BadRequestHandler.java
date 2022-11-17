package com.ganaway.backend.exceptions;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

@ControllerAdvice
@Slf4j
public class BadRequestHandler {

    @ResponseStatus(HttpStatus.OK)
    @ExceptionHandler(HttpMessageNotReadableException.class)
    @ResponseBody
    public ErrorBean handleHttpMessageNotReadableException(HttpMessageNotReadableException e) {
        log.info("Here");
        ErrorBean errorBean = new ErrorBean();
        errorBean.setMessage(e.getMessage());
        return errorBean;
    }

    class ErrorBean {
        private String message;

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }
    }
}
