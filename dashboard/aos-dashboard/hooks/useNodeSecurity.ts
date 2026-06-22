import { useQuery } from "@tanstack/react-query";
import { getNodes } from "@/services/nodes.service";

export function useNodeSecurity(node: string) {
  return useQuery({
    queryKey: ["node-security", node],
    queryFn: async () => {
      const nodes = await getNodes();

      return nodes.find((n: any) => n.node === node);
    },
    enabled: !!node,
  });
}
