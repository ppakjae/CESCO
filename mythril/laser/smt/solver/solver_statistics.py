from time import time

from mythril.support.support_utils import Singleton

from typing import Callable


def stat_smt_query(func: Callable):
    """Measures statistics for annotated smt query check function
    주석이 달린 SMT 쿼리 확인 함수에 대한 통계를 측정합니다.
    """
    stat_store = SolverStatistics()

    def function_wrapper(*args, **kwargs):
        if not stat_store.enabled:
            return func(*args, **kwargs)

        stat_store.query_count += 1
        begin = time()

        result = func(*args, **kwargs)

        end = time()
        stat_store.solver_time += end - begin

        return result

    return function_wrapper


class SolverStatistics(object, metaclass=Singleton):
    """Solver Statistics Class

    Keeps track of the important statistics around smt queries
    솔버 통계 클래스

    SMT 쿼리를 중심으로 중요한 통계를 추적합니다
    """

    def __init__(self):
        self.enabled = False
        self.query_count = 0
        self.solver_time = 0

    def __repr__(self):
        return "Query count: {} \nSolver time: {}".format(
            self.query_count, self.solver_time
        )
