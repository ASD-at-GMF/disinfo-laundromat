<!-- Wrapper component based on https://www.bits-ui.com/docs/components/select -->
<script lang="ts">
	import { Select, type Selected, type SelectProps } from 'bits-ui';
  import { onMount } from 'svelte';
	import type { LabeledValue } from '$types';

	export let id: string;
	export let name: string;
	export let selected: Selected<unknown>; 
	export let onSelectedChange: (value: string, name: string) => void;
	let className: string | undefined = undefined;
	export { className as class };

	function handleSelectedChange(value: Selected<unknown> | undefined) {
		if (value && value.value !== null) {
			onSelectedChange(value.value as string, name);
		}
	}

 onMount(() => {
		// update parent with default selected value
		handleSelectedChange(selected); 
 });

</script>

<div {id} class={className}>
	<Select.Root {name} {selected} onSelectedChange={handleSelectedChange} {...$$restProps}>
		<Select.Trigger
			class="h-input border-border-input bg-background placeholder:text-foreground-alt/50 focus:ring-foreground focus:ring-offset-background inline-flex items-center border px-[11px]  text-sm transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2"
			aria-label="Select a item"
		>
			<Select.Value class="text-sm" />
		</Select.Trigger>
		<Select.Content
			class="border-muted bg-background shadow-popover w-full border px-1 py-3 outline-none"
			sideOffset={8}>
		<slot/>
		</Select.Content>
		<select.input />
	</Select.Root>
</div>
