"""Labels and filters write methods for GmailClient.

Co-located because both are mailbox-settings/metadata write paths and
each is too small (~9 to ~19 LOC) to warrant its own file under the
project's "300 LOC max" discipline. If filters grow their own
template surface in a future PR, splitting this module into
`_labels.py` and `_filters.py` is one trivial follow-up away.
"""

from __future__ import annotations

from typing import Any

from ..gmail_id import validate_gmail_id


class _LabelsFiltersWriteMixin:
    """Labels and filters write methods."""

    # ---- write: labels ------------------------------------------------------

    async def create_label(self, *, body: dict[str, Any]) -> dict[str, Any]:
        return await self._post("/users/me/labels", body=body)

    async def update_label(
        self,
        *,
        label_id: str,
        body: dict[str, Any],
    ) -> dict[str, Any]:
        # validate ID before path interpolation.
        label_id = validate_gmail_id(label_id, field="label_id")
        return await self._put(f"/users/me/labels/{label_id}", body=body)

    async def delete_label(self, *, label_id: str) -> dict[str, Any]:
        # validate ID before path interpolation.
        label_id = validate_gmail_id(label_id, field="label_id")
        return await self._delete(f"/users/me/labels/{label_id}")

    # ---- write: filters -----------------------------------------------------

    async def create_filter(self, *, body: dict[str, Any]) -> dict[str, Any]:
        return await self._post("/users/me/settings/filters", body=body)

    async def delete_filter(self, *, filter_id: str) -> dict[str, Any]:
        # validate ID before path interpolation.
        filter_id = validate_gmail_id(filter_id, field="filter_id")
        return await self._delete(f"/users/me/settings/filters/{filter_id}")
