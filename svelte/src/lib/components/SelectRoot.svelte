<script lang="ts">
	import { Select, type SelectProps } from 'bits-ui';
	import { cn } from '$utils';
</script>

<Select.Root 
	{...$$restProps}>
	<slot />
</Select.Root>
