package handler

import (
	"net/http"

	"menii-auth/internal/models"
	"menii-auth/internal/service"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
)

type AuthHandler struct {
	svc      service.AuthService
	validate *validator.Validate
}

func NewAuthHandler(svc service.AuthService) *AuthHandler {
	return &AuthHandler{
		svc:      svc,
		validate: validator.New(),
	}
}

func (h *AuthHandler) Register(c echo.Context) error {
	req := new(models.RegisterRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    "INVALID_REQUEST",
			Message: "invalid request body",
		})
	}

	if err := h.validate.Struct(req); err != nil {
		return c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    "VALIDATION_ERROR",
			Message: err.Error(),
		})
	}

	res, err := h.svc.Register(req)
	if err != nil {
		return c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    "ERROR",
			Message: err.Error(),
		})
	}

	return c.JSON(http.StatusOK, models.APIResponse{
		Code:    "SUCCESS",
		Message: "register success",
		Data:    res,
	})
}

func (h *AuthHandler) Login(c echo.Context) error {
	req := new(models.LoginRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    "INVALID_REQUEST",
			Message: "invalid request body",
		})
	}

	if err := h.validate.Struct(req); err != nil {
		return c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    "VALIDATION_ERROR",
			Message: err.Error(),
		})
	}

	res, err := h.svc.Login(req)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, models.APIResponse{
			Code:    "UNAUTHORIZED",
			Message: err.Error(),
		})
	}

	return c.JSON(http.StatusOK, models.APIResponse{
		Code:    "SUCCESS",
		Message: "login success",
		Data:    res,
	})
}
