from pydantic import BaseModel, Field


class PageInfo(BaseModel):
    number: int = 0
    size: int = 10
    total_pages: int = Field(0, alias="totalPages")
    total_resources: int = Field(0, alias="totalResources")

    model_config = {"populate_by_name": True}


class Link(BaseModel):
    rel: str
    href: str


class SearchCriterion(BaseModel):
    field: str
    operator: str
    value: str
