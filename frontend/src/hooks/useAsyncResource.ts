import { useEffect, useRef, useState } from "react";

type AsyncState<T> = {
  data: T | null;
  error: string | null;
  isLoading: boolean;
  isRefreshing: boolean;
};

export function useAsyncResource<T>(
  load: (signal: AbortSignal) => Promise<T>,
  dependencies: readonly unknown[],
) {
  const loadRef = useRef(load);
  const [state, setState] = useState<AsyncState<T>>({
    data: null,
    error: null,
    isLoading: true,
    isRefreshing: false,
  });
  const [refreshIndex, setRefreshIndex] = useState(0);
  loadRef.current = load;

  useEffect(() => {
    const controller = new AbortController();
    setState((current) => ({
      data: current.data,
      error: null,
      isLoading: current.data === null,
      isRefreshing: current.data !== null,
    }));

    loadRef.current(controller.signal)
      .then((data) => {
        setState({ data, error: null, isLoading: false, isRefreshing: false });
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted) {
          return;
        }

        const message = error instanceof Error ? error.message : "Unexpected request error.";
        setState((current) => ({
          data: current.data,
          error: message,
          isLoading: false,
          isRefreshing: false,
        }));
      });

    return () => controller.abort();
  }, [refreshIndex, ...dependencies]);

  return {
    ...state,
    refresh: () => setRefreshIndex((current) => current + 1),
  };
}
