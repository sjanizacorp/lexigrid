"""Bounded UI diagnostics; never accepts document text or exception messages.
Author: Shahryar Jahangir, Aniza Inc.
"""
from typing import Literal
from fastapi import Depends
from pydantic import BaseModel,ConfigDict,Field
from .main import app,principal,User,emit_event


class ClientEvent(BaseModel):
    model_config=ConfigDict(extra='forbid')
    activity:Literal['reviewed_import','bulk_import']
    event:Literal['framework_required','framework_created','selection_required','selection_all','selection_cleared','fields_required','confirmation_opened','cancelled','source_changed','network_error','client_error']
    kind:Literal['requirements','controls','frameworks','policies']
    selected_count:int=Field(default=0,ge=0)
    line:int=Field(default=0,ge=0,le=100000)


@app.post('/api/client-events',status_code=202)
def client_event(body:ClientEvent,u:User=Depends(principal)):
    emit_event('operations','ui.'+body.activity+'.'+body.event,
               outcome='error' if body.event in {'network_error','client_error'} else 'info',
               actor_id=u.id,tenant_id=u.tenant_id,kind=body.kind,selected_count=body.selected_count,line=body.line)
    return {'recorded':True}
