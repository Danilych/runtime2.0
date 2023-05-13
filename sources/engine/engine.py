
from contextlib import contextmanager
from threading import local, current_thread, enumerate as enumerate_threads

import settings
import managers

from logs import log
from memory import COMPUTE_CONTEXT, RENDER_CONTEXT, WYSIWYG_CONTEXT
from utils.profiling import profiler
from utils.threads import stop as stop_threads
# from utils.statistics import statistics
from .exceptions import RenderTermination
from .contexts import RenderContext, WysiwygContext


class EngineLocal(local):

    application = None


class EngineThreads(set):

    def filter(self, uuid):
        return {thread for thread in self if thread.application == uuid}

    def stop(self, uuid=None):
        stop_threads(lambda thread: getattr(thread, "application", None) == uuid if uuid else getattr(thread, "application", None) is not None)


class Engine(object):

    def __init__(self):
        self._storage = EngineLocal()

    application = property(lambda self: self._storage.application)
    threads = property(lambda self: EngineThreads(thread for thread in enumerate_threads()
            if getattr(thread, "application", None) is not None))

    def select(self, application=None):
        if isinstance(application, basestring):
            application = managers.memory.applications[application]
        previous = self._storage.application
        if application is not previous:
            if settings.DETAILED_LOGGING:
                log.write("Select %s" % (application or "no application"))
            self._storage.application = application
            # TODO: check this thread using
            current_thread().application = application.id if application else None
        return previous

    @contextmanager
    def context(self, application=None):
        if application:
            previous = self.select(application)
        try:
            yield
        finally:
            if application:
                self.select(previous)

    def compute(self, object, parent=None):
        if settings.DETAILED_LOGGING:
            log.write("Compute %s" % object)
        previous = self.select(object.application)
        managers.script_manager.constrain(settings.COMPUTE_TIMEOUT)
        try:
            with profiler:
                instance = object.factory(COMPUTE_CONTEXT)(parent)
                instance.recompute()
        finally:
            managers.script_manager.revoke()
            self.select(previous)

    def render(self, object, parent=None, render_type=None):
        if settings.DETAILED_LOGGING:
            log.write("Render %s" % object)
            
        previous = self.select(object.application)

        managers.script_manager.constrain(settings.RENDER_TIMEOUT)

        try:
            with profiler:
                
                instance = object.factory(RENDER_CONTEXT)(parent)
                print("RENDER CONTEXT = " + str(RENDER_CONTEXT))
                print("PARENT = " + str(parent))
                print("INSTANCE = " + str(instance) + " === " + str(type(instance)))
                instance.execute()

                return instance.render()
        except RenderTermination:
            return ""
        finally:
            managers.script_manager.revoke()
            self.select(previous)
            # statistics.show("Render %s" % object)

    @contextmanager
    def start_render(self, object, parent=None, render_type=None):
        if settings.DETAILED_LOGGING:
            log.write("Render %s" % object)
        previous = self.select(object.application)
        managers.script_manager.constrain(settings.RENDER_TIMEOUT)
        try:
            with profiler:
                yield RenderContext(object.factory(RENDER_CONTEXT)(parent))
        except RenderTermination:
            return
        finally:
            managers.script_manager.revoke()
            self.select(previous)
            # statistics.show("Render %s" % object)

    def wysiwyg(self, object, parent=None):
        if settings.DETAILED_LOGGING:
            log.write("Wysiwyg %s" % object)
        previous = self.select(object.application)
        managers.script_manager.constrain(settings.WYSIWYG_TIMEOUT)
        try:
            with profiler:
                instance = object.factory(WYSIWYG_CONTEXT)(parent)
                return instance.wysiwyg()
        finally:
            managers.script_manager.revoke()
            self.select(previous)

    @contextmanager
    def start_wysiwyg(self, object, parent=None):
        if settings.DETAILED_LOGGING:
            log.write("Wysiwyg %s" % object)
        previous = self.select(object.application)
        managers.script_manager.constrain(settings.WYSIWYG_TIMEOUT)
        try:
            with profiler:
                yield WysiwygContext(object.factory(WYSIWYG_CONTEXT)(parent))
        finally:
            managers.script_manager.revoke()
            self.select(previous)

    def execute(self, action, parent=None, context=None, render=None):
        log.write("Execute%s %s" % (" and render" if render else "", action))
        previous = self.select(action.owner.application)
        managers.script_manager.constrain(settings.SCRIPT_TIMEOUT)
        try:
            # try:
            #     namespace = managers.request_manager.get_request().session().context
            # except VDOM_exception:
            #     namespace = {}
            if action.owner.is_application:
                # action.execute(namespace=namespace)
                with profiler:
                    action.execute()
            else:
                with profiler:
                    instance = action.owner.factory(context or action.id)(parent)
                    # instance.execute(namespace=namespace)
                    instance.execute()
                    return instance.separate_render() if render else None
        except RenderTermination:
            return "" if render else None
        finally:
            managers.script_manager.revoke()
            self.select(previous)
            # statistics.show("Execute%s %s" % (" and render" if render else "", action))

    def terminate(self):
        if settings.DETAILED_LOGGING:
            log.write("Terminate render")
        # from utils.tracing import format_thread_trace
        # log.debug(format_thread_trace(statements=False, skip=("terminate", "redirect"), until="scripting.executable"))
        raise RenderTermination


VDOM_engine = Engine
