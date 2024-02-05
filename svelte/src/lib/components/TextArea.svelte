<script lang="ts">
	import { cn } from '$utils';
  export let value : string = '';
  export let placeholder : string = '';
  export let rows : number  = 4;
  export let cols : number  = 50;
  export let onInput : (value: string) => void;
	let className : 'string' = '';
	export {className as class}

  function handleInputChange(event: Event) {
    const { value } = event.target as HTMLTextAreaElement;
    if (onInput) {
      onInput(value);
    }
  }
</script>


<textarea 
	bind:value placeholder={placeholder} 
	rows="4"
	cols="50" 
	on:input={handleInputChange}
	class={cn('', className)}/>
