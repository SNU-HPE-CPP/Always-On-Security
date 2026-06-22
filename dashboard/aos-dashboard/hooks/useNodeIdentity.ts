import { useQuery } from "@tanstack/react-query";
import { getNodeIdentity } from "@/services/nodes.service";

export function useNodeIdentity(node: string) {
  return useQuery({
    queryKey: ["node-identity", node],
    queryFn: async () => {
      const identities = await getNodeIdentity();

      return identities.find((item: any) => item.node === node);
    },
    enabled: !!node,
  });
}
