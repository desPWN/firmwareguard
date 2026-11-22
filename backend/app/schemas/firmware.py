import uuid
from datetime import datetime

from pydantic import BaseModel


class FirmwareUploadResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    original_filename: str | None
    sha256: str
    file_size: int | None
    version_label: str | None = None
    created_at: datetime


class FirmwareUpdate(BaseModel):
    version_label: str | None = None


class FirmwareDetailResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    project_id: uuid.UUID
    original_filename: str | None
    sha256: str
    file_size: int | None
    storage_path: str | None
    extracted_path: str | None
    extraction_dir: str | None = None
    architecture: str | None
    endianness: str | None
    os_info: str | None
    kernel_path: str | None
    version_label: str | None = None
    unpack_log: str | None
    created_at: datetime


# ── Firmware Image Metadata schemas ──


class FirmwareSectionResponse(BaseModel):
    offset: int
    size: int | None
    type: str
    description: str


class UBootHeaderResponse(BaseModel):
    magic: str
    header_crc: str
    timestamp: int
    data_size: int
    load_address: str
    entry_point: str
    data_crc: str
    os_type: str
    architecture: str
    image_type: str
    compression: str
    name: str


class MTDPartitionResponse(BaseModel):
    name: str
    offset: int | None
    size: int


class FirmwareMetadataResponse(BaseModel):
    file_size: int
    sections: list[FirmwareSectionResponse] = []
    uboot_header: UBootHeaderResponse | None = None
    uboot_env: dict[str, str] = {}
    mtd_partitions: list[MTDPartitionResponse] = []


# ── Entropy & Decryption schemas ──


class EntropyBlockResponse(BaseModel):
    offset: int
    size: int
    entropy: float


class FirmwareEntropyResponse(BaseModel):
    file_size: int
    overall_entropy: float
    min_entropy: float
    max_entropy: float
    high_entropy_ratio: float
    verdict: str
    detected_format: str | None = None
    detected_format_label: str | None = None
    known_signatures: list[str] = []
    summary: str
    blocks: list[EntropyBlockResponse] = []


class FirmwareDecryptRequest(BaseModel):
    mode: str = "custom"  # "auto" | "custom"
    algorithm: str = "aes-128-cbc"
    key: str = ""
    key_format: str = "hex"  # "hex" | "utf8"
    iv: str = ""
    offset: int = 0
    unpad: bool = False
    auto_unpack: bool = True


class FirmwareDecryptResponse(BaseModel):
    success: bool
    method: str
    output_size: int
    post_entropy: float
    known_signatures: list[str] = []
    unpack_started: bool = False
    message: str
