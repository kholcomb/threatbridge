from enum import Enum
from pydantic import BaseModel, Field


class IOCType(str, Enum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    PORT = "port"
    PROTOCOL = "protocol"
    FILE_HASH_MD5 = "file_hash_md5"
    FILE_HASH_SHA1 = "file_hash_sha1"
    FILE_HASH_SHA256 = "file_hash_sha256"
    FILE_PATH = "file_path"
    FILE_NAME = "file_name"
    PROCESS_NAME = "process_name"
    COMMAND_LINE = "command_line"
    REGISTRY_KEY = "registry_key"
    BEHAVIORAL = "behavioral"
    USER_AGENT = "user_agent"
    HTTP_HEADER = "http_header"
    MUTEX = "mutex"


class IOCConfidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFERRED = "inferred"


class IOC(BaseModel):
    ioc_type: IOCType
    value: str
    confidence: IOCConfidence
    context: str = ""
    source: str = ""
    related_technique_ids: list[str] = Field(default_factory=list)


class IOCBundle(BaseModel):
    cve_id: str
    network: list[IOC] = Field(default_factory=list)
    file: list[IOC] = Field(default_factory=list)
    process: list[IOC] = Field(default_factory=list)
    behavioral: list[IOC] = Field(default_factory=list)

    def all_iocs(self) -> list[IOC]:
        return self.network + self.file + self.process + self.behavioral

    def by_type(self, ioc_type: IOCType) -> list[IOC]:
        return [ioc for ioc in self.all_iocs() if ioc.ioc_type == ioc_type]
