package api

import (
	"net/http"

	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/models"
)

// adminUserSignInLogs returns paginated sign-in logs for a given user (admin-only)
func (a *API) adminUserSignInLogs(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	pageParams, err := paginate(r)
	if err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Bad Pagination Parameters: %v", err)
	}

	user := getUser(ctx)

	logs, err := models.FindSignInLogsByUser(db, user.ID, pageParams)
	if err != nil {
		return apierrors.NewInternalServerError("Error searching for sign in logs").WithInternalError(err)
	}

	addPaginationHeaders(w, r, pageParams)
	return sendJSON(w, http.StatusOK, logs)
}


