"""Helpers for agent frameworks whose model clients cannot be passed in.

Most frameworks take an SDK client: hand them ``pragmatic.wrap(client)``
(the OpenAI Agents SDK's ``set_default_openai_client``, a Pydantic AI
provider's ``anthropic_client`` or ``openai_client``). The modules here
cover the ones that build their clients themselves:

- ``pragmatic.integrations.langchain.journal(llm)`` for LangChain's
  ``ChatAnthropic`` and ``ChatOpenAI`` (and so LangGraph agents built on
  them).
"""
