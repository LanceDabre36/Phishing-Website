package com.phishguard.config;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.resource.NoResourceFoundException;

/** Renders the branded 404 page for unmapped paths and missing static resources. */
@ControllerAdvice
public class PageErrorAdvice {

    @ExceptionHandler(NoResourceFoundException.class)
    public ModelAndView notFound() {
        return new ModelAndView("error/404", HttpStatus.NOT_FOUND);
    }
}
