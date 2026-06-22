import { useMutation } from "@tanstack/react-query";

import { resetSystem } from "@/services/system.service";

export function useSystemReset() {
  return useMutation({
    mutationFn: resetSystem,
  });
}
