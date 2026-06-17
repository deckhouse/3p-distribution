package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/docker/distribution/registry/quota"
)

// fixedLimit is a quota.LimitProvider that always returns the same limit.
type fixedLimit int64

func (l fixedLimit) Limit(_ context.Context, _ string) (int64, error) { return int64(l), nil }

// fixedFootprint is a quota.FootprintProvider that always returns the same footprint.
type fixedFootprint int64

func (f fixedFootprint) Footprint(_ context.Context, _ string) (int64, error) { return int64(f), nil }

// TestBlobUploadQuotaRejectionKeepsUploadSession verifies that rejecting a blob
// for quota reasons does NOT destroy the upload session. Cancelling the upload
// on rejection (the previous behaviour) removed the session, so a client retry
// of the finalizing PUT — go-containerregistry retries on transient/connection
// errors — resolved to ErrBlobUploadUnknown (BLOB_UPLOAD_UNKNOWN) instead of a
// clean, repeatable quota error. This reproduces a registry client's flow:
// PATCH the blob bytes, then PUT to finalize.
func TestBlobUploadQuotaRejectionKeepsUploadSession(t *testing.T) {
	env := newTestEnv(t, false)
	defer env.Shutdown()

	// Any blob larger than 1 byte exceeds the quota.
	env.app.quotaEnforcer = quota.NewEnforcer(fixedLimit(1), fixedFootprint(0))

	args := makeBlobArgs(t)

	uploadURLBase, _ := startPushLayer(t, env, args.imageName)

	// PATCH the blob bytes (not gated by the quota; quota is enforced on commit).
	chunkResp, dgst, err := doPushChunk(t, uploadURLBase, args.layerFile)
	if err != nil {
		t.Fatalf("unexpected error pushing chunk: %v", err)
	}
	checkResponse(t, "pushing blob chunk", chunkResp, http.StatusAccepted)
	finalizeURL := chunkResp.Header.Get("Location")
	chunkResp.Body.Close()

	// Finalizing PUT: must be rejected with 413 / quota exceeded.
	resp, err := doPushLayer(t, env.builder, args.imageName, dgst, finalizeURL, nil)
	if err != nil {
		t.Fatalf("unexpected error finalizing blob: %v", err)
	}
	checkResponse(t, "quota-rejected blob PUT", resp, http.StatusRequestEntityTooLarge)
	checkBodyHasErrorCodes(t, "quota-rejected blob PUT", resp, ErrorCodeQuotaExceeded)

	// Retry the same finalizing PUT. The upload session must still exist, so the
	// registry re-evaluates and rejects again with 413 — never 404
	// BLOB_UPLOAD_UNKNOWN (which is what a destroyed session would produce).
	retry, err := doPushLayer(t, env.builder, args.imageName, dgst, finalizeURL, nil)
	if err != nil {
		t.Fatalf("unexpected error retrying finalize: %v", err)
	}
	defer retry.Body.Close()
	if retry.StatusCode == http.StatusNotFound {
		t.Fatalf("retry after quota rejection returned 404 (BLOB_UPLOAD_UNKNOWN): the upload session was destroyed")
	}
	checkResponse(t, "retry after quota rejection", retry, http.StatusRequestEntityTooLarge)
	checkBodyHasErrorCodes(t, "retry after quota rejection", retry, ErrorCodeQuotaExceeded)
}
