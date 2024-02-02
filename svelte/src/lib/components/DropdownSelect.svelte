<!-- Wrapper component based on https://www.bits-ui.com/docs/components/select -->
<script lang="ts">
	import { Select, type Selected, type SelectProps } from 'bits-ui';
	import type { LabeledValue } from '$types';
  //import { createEventDispatcher } from 'svelte';

  //const dispatch = createEventDispatcher();
	let id: string;
	let items: LabeledValue[];
	let name: string;
	let onSelectedChange: (value: any, name: string) => void;
	let className: string | undefined = undefined;

	function handleSelectedChange(value: Selected<unknown> | undefined) {
		if (value && value.value !== null) {
			onSelectedChange(value.value, name);
		}
	}

	export {
		id,	
		items,
		name,
		onSelectedChange,
		className as class,
	};
</script>

<div {id} class={className}>
	<Select.Root {name} onSelectedChange={handleSelectedChange} {...$$restProps}>
		<Select.Trigger
			class="h-input border-border-input bg-background placeholder:text-foreground-alt/50 focus:ring-foreground focus:ring-offset-background inline-flex items-center border px-[11px]  text-sm transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2"
			aria-label="Select a item"
		>
			<Select.Value class="text-sm"/>
		</Select.Trigger>
		<Select.Content
			class="border-muted bg-background shadow-popover w-full border px-1 py-3 outline-none"
			sideOffset={8}
		>
			{#each items as item}
				<Select.Item
					class="rounded-button data-[highlighted]:bg-muted flex h-10 w-full select-none items-center py-3 pl-5 pr-1.5 text-sm outline-none transition-all duration-75"
					value={item.value}
					label={item.label}>
					{item.label}
					<Select.ItemIndicator class="ml-auto" asChild={false}></Select.ItemIndicator>
				</Select.Item>
			{/each}
		</Select.Content>
		<select.input/>
	</Select.Root>
</div>
