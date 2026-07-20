export interface Principal {
  agentId: string;
  name: string;
  tenant: string;
  onBehalfOf: string[]; // ordered delegation chain of agent names (root first)
}
