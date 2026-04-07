package handler

import (
	"net/http"

	"menii-auth/internal/models"
	"menii-auth/internal/service"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
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

	return c.JSON(http.StatusCreated, models.APIResponse{
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
		switch err {
		case service.ErrInvalidCredentials:
			return c.JSON(http.StatusUnauthorized, models.APIResponse{
				Code:    "INVALID_CREDENTIALS",
				Message: "invalid username or password",
			})
		case service.ErrAccountNotVerified:
			return c.JSON(http.StatusForbidden, models.APIResponse{
				Code:    "ACCOUNT_NOT_VERIFIED",
				Message: "account is not verified",
				Data: map[string]string{
					"next_action": "VERIFY_OTP",
				},
			})
		case service.ErrAccountSuspended:
			return c.JSON(http.StatusForbidden, models.APIResponse{
				Code:    "ACCOUNT_SUSPENDED",
				Message: "account has been suspended",
			})
		default:
			return c.JSON(http.StatusInternalServerError, models.APIResponse{
				Code:    "ERROR",
				Message: err.Error(),
			})
		}
	}

	return c.JSON(http.StatusOK, models.APIResponse{
		Code:    "SUCCESS",
		Message: "login success",
		Data:    res,
	})
}

func (h *AuthHandler) Logout(c echo.Context) error {
	sessionID, ok := c.Get("session_id").(uuid.UUID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, models.APIResponse{
			Code:    "UNAUTHORIZED",
			Message: "invalid session",
		})
	}

	if err := h.svc.Logout(sessionID); err != nil {
		return c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    "ERROR",
			Message: err.Error(),
		})
	}

	return c.JSON(http.StatusOK, models.APIResponse{
		Code:    "SUCCESS",
		Message: "logout success",
		Data: map[string]bool{
			"logged_out": true,
		},
	})
}

func (h *AuthHandler) Refresh(c echo.Context) error {
	req := new(models.RefreshRequest)
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

	res, err := h.svc.RefreshToken(req)
	if err != nil {
		switch err {
		case service.ErrInvalidRefreshToken:
			return c.JSON(http.StatusUnauthorized, models.APIResponse{
				Code:    "INVALID_REFRESH_TOKEN",
				Message: "invalid refresh token",
			})
		case service.ErrSessionExpired:
			return c.JSON(http.StatusUnauthorized, models.APIResponse{
				Code:    "SESSION_EXPIRED",
				Message: "session expired",
			})
		default:
			return c.JSON(http.StatusInternalServerError, models.APIResponse{
				Code:    "ERROR",
				Message: err.Error(),
			})
		}
	}

	return c.JSON(http.StatusOK, models.APIResponse{
		Code:    "SUCCESS",
		Message: "token refreshed",
		Data:    res,
	})
}

func (h *AuthHandler) RequestOTP(c echo.Context) error {
	req := new(models.OtpRequestPayload)
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

	res, err := h.svc.RequestOTP(req)
	if err != nil {
		if rateLimitErr, ok := err.(*service.OtpRateLimitError); ok {
			return c.JSON(http.StatusTooManyRequests, models.APIResponse{
				Code:    "OTP_RATE_LIMITED",
				Message: "please wait before requesting another otp",
				Data: map[string]int{
					"retry_after_sec": rateLimitErr.RetryAfterSec,
				},
			})
		}

		switch err {
		case service.ErrUserNotFound:
			return c.JSON(http.StatusNotFound, models.APIResponse{
				Code:    "USER_NOT_FOUND",
				Message: "user not found",
			})
		default:
			return c.JSON(http.StatusInternalServerError, models.APIResponse{
				Code:    "ERROR",
				Message: err.Error(),
			})
		}
	}

	return c.JSON(http.StatusOK, models.APIResponse{
		Code:    "SUCCESS",
		Message: "otp sent",
		Data:    res,
	})
}

func (h *AuthHandler) VerifyOTP(c echo.Context) error {
	req := new(models.VerifyOtpRequest)
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

	res, err := h.svc.VerifyOTP(req)
	if err != nil {
		switch err {
		case service.ErrOtpExpired:
			return c.JSON(http.StatusGone, models.APIResponse{
				Code:    "OTP_EXPIRED",
				Message: "otp expired",
			})
		case service.ErrOtpInvalid:
			return c.JSON(http.StatusUnauthorized, models.APIResponse{
				Code:    "OTP_INVALID",
				Message: "invalid otp",
			})
		case service.ErrOtpMaxAttemptsExceeded:
			return c.JSON(http.StatusForbidden, models.APIResponse{
				Code:    "OTP_MAX_ATTEMPTS_EXCEEDED",
				Message: "otp verification failed",
			})
		default:
			return c.JSON(http.StatusInternalServerError, models.APIResponse{
				Code:    "ERROR",
				Message: err.Error(),
			})
		}
	}

	return c.JSON(http.StatusOK, models.APIResponse{
		Code:    "SUCCESS",
		Message: "otp verified",
		Data:    res,
	})
}
