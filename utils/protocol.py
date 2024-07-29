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
    logic_answer: Union[str, object] = pydantic.Field(
        "", description="Short logic answer as a summary of the logic reasoning."
    )
    logic_reasoning: str = pydantic.Field(
        "",
        description="Reasoning when answering the logic question",
    )
    # SYNAPSE INFORMATION
    category: str = pydantic.Field(
        "",
        description="One of the categories in the Validator main.",
    )
    timeout: int = pydantic.Field(
        64,
        description="Timeout for the miner to answer the logic question.",
    )