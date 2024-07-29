import pydantic
from typing import Union


class LogicSynapse(pydantic.BaseModel):
    """
    Logic Synapse for the LogicNet protocol
    """

    # MINER NEED TO FILL THIS INFORMATION
    logic_question: str = pydantic.Field(
        "",
        description="Logic question to be answered by miner. It can be noised question from the raw logic question from synthetic loop.",
    )
    # SYNAPSE INFORMATION
    category: str = pydantic.Field(
        "",
        description="One of the categories in the Validator main.",
    )