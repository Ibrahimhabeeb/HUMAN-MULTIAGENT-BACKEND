from datetime import datetime
from typing import Annotated

from pydantic import AfterValidator

from models.common import as_utc

# Times read back from SQLite lose their timezone; marking them UTC lets the frontend show the right time.
UtcDatetime = Annotated[datetime, AfterValidator(as_utc)]
